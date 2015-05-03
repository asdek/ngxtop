"""ngxtop - ad-hoc query for nginx access log.

Usage:
    ngxtop [options]
    ngxtop [options] (print|top|avg|sum) <var> ...
    ngxtop info
    ngxtop [options] query <query> ...

Options:
    -l <file>, --access-log <file>  access log file to parse.
    -f <format>, --log-format <format>  log format as specify in log_format directive. [default: combined]
    --no-follow  ngxtop default behavior is to ignore current lines in log
                     and only watch for new lines as they are written to the access log.
                     Use this flag to tell ngxtop to process the current content of the access log instead.
    -t <seconds>, --interval <seconds>  report interval when running in follow mode [default: 2.0]

    -g <var>, --group-by <var>  group by variable [default: request_path:TEXT]
    -u <var>, --uni-count <var>  count unique values by [default: remote_addr]
    -r <seconds>, --auto-rotate <seconds>  time of existence records in the table [default: 0]
    -w <var>, --having <expr>  having clause [default: 1]
    -o <var>, --order-by <var>  order of output for default query [default: count]
    -n <number>, --limit <number>  limit the number of records included in report for top command [default: 10]
    -a <exp> ..., --a <exp> ...  add exp (must be aggregation exp: sum, avg, min, max, etc.) into output

    -v, --verbose  more verbose output
    -d, --debug  print every line and parsed record
    -h, --help  print this help message.
    --version  print version information.

    Advanced / experimental options:
    -c <file>, --config <file>  allow ngxtop to parse nginx config file for log format and location.
    -i <filter-expression>, --filter <filter-expression>  filter in, records satisfied given expression are processed.
    -p <filter-expression>, --pre-filter <filter-expression> in-filter expression to check in pre-parsing phase.
    -r <replace-expression>, --time-rpl-expr <replace-expression> pre-expression to replace in field time_local of log

Examples:
    All examples read nginx config file for access log location and format.
    If you want to specify the access log file and / or log format, use the -f and -a options.

    "top" like view of nginx requests
    $ ngxtop

    Top 10 requested path with status 404:
    $ ngxtop top request_path --filter 'status == 404'

    Top 10 requests with highest total bytes sent
    $ ngxtop --order-by 'avg(bytes_sent) * count'

    Top 10 remote address, e.g., who's hitting you the most
    $ ngxtop --group-by remote_addr:TEXT

    Print requests with 4xx or 5xx status, together with status and http referer
    $ ngxtop -i 'status >= 400' print request status http_referer

    Average body bytes sent of 200 responses of requested path begin with 'foo':
    $ ngxtop avg bytes_sent --filter 'status == 200 and request_path.startswith("foo")'

    Analyze apache access log from remote machine using 'common' log format
    $ ssh remote tail -f /var/log/apache2/access.log | ngxtop -f common
"""
from __future__ import print_function
import atexit
from contextlib import closing
import curses
import logging
import os
import sqlite3
import time
import sys
import signal
import re
import binascii
import dateutil.parser as dt_parser
from datetime import datetime as dt

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

from docopt import docopt
import tabulate

from config_parser import detect_log_config, detect_config_path, extract_variables, build_pattern
from utils import error_exit


DEFAULT_QUERIES = [
    ('Summary:',
     '''SELECT
       count(1)                                    AS count,
       avg(bytes_sent)                             AS avg_bytes_sent,
       count(CASE WHEN status_type = 2 THEN 1 END) AS '2xx',
       count(CASE WHEN status_type = 3 THEN 1 END) AS '3xx',
       count(CASE WHEN status_type = 4 THEN 1 END) AS '4xx',
       count(CASE WHEN status_type = 5 THEN 1 END) AS '5xx'
     FROM log
     ORDER BY %(--order-by)s DESC
     LIMIT %(--limit)s'''),

    ('Detailed:',
     '''SELECT
       %(--group-by)s,
       count(1)                                    AS count,
       count(DISTINCT %(--uni-count)s)             AS uni_%(--uni-count)s,
       max(datetime(time_local))                   AS last_timestamp,
       avg(bytes_sent)                             AS avg_bytes_sent,
       count(CASE WHEN status_type = 2 THEN 1 END) AS '2xx',
       count(CASE WHEN status_type = 3 THEN 1 END) AS '3xx',
       count(CASE WHEN status_type = 4 THEN 1 END) AS '4xx',
       count(CASE WHEN status_type = 5 THEN 1 END) AS '5xx'
     FROM log
     GROUP BY %(--group-by)s
     HAVING %(--having)s
     ORDER BY %(--order-by)s DESC
     LIMIT %(--limit)s''')
]

DEFAULT_REPLACE_EXPRESSION = {
    'in_rpl_expr': r'^(?P<d>[0-9]{2})/(?P<m>[0-9]{2})/(?P<Y>[0-9]{4}):'
                   '(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}) '
                   '(?P<tzs>[+-])(?P<tzH>[0-9]{2})(?P<tzM>[0-9]{2})$',
    'out_rpl_expr': r'\g<Y>-\g<m>-\g<d> \g<time>\g<tzs>\g<tzH>:\g<tzM>'
}

DEFAULT_REPLACE_MONTH = {'Jan': '01',
                         'Feb': '02',
                         'Mar': '03',
                         'Apr': '04',
                         'May': '05',
                         'Jun': '06',
                         'Jul': '07',
                         'Aug': '08',
                         'Sep': '09',
                         'Oct': '10',
                         'Nov': '11',
                         'Dec': '12'}

DEFAULT_FIELDS = dict({'status_type': 'INT', 'bytes_sent': 'INT', 'request_path': 'TEXT', 'time_local': 'DATETIME'})

DEFAULT_LIMIT_TIME = 300

DEFAULT_REGEXP_SPLITTER = r'(?P<key>.*):(?P<value>.*)'


# ======================
# generator utilities
# ======================
def follow(the_file):
    """
    Follow a given file and yield new lines when they are available, like `tail -f`.
    """
    with open(the_file) as f:
        f.seek(0, 2)  # seek to eof
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)  # sleep briefly before trying again
                continue
            yield line


def map_field(field, func, dict_sequence):
    """
    Apply given function to value of given key in every dictionary in sequence and
    set the result as new value for that key.
    """
    for item in dict_sequence:
        try:
            item[field] = func(item.get(field, None))
            yield item
        except ValueError:
            pass


def fix_month(text):
    return re.sub('([a-zA-Z]{3})', lambda m: DEFAULT_REPLACE_MONTH[m.group(1)], text)


def add_field(field, func, dict_sequence):
    """
    Apply given function to the record and store result in given field of current record.
    Do nothing if record already contains given field.
    """
    for item in dict_sequence:
        if field not in item:
            item[field] = func(item)
        yield item


def trace(sequence, phase=''):
    for item in sequence:
        logging.debug('%s:\n%s', phase, item)
        yield item


# ======================
# Access log parsing
# ======================
def parse_request_path(record):
    if 'request_uri' in record:
        uri = record['request_uri']
    elif 'request' in record:
        uri = ' '.join(record['request'].split(' ')[1:-1])
    else:
        uri = None
    return urlparse.urlparse(uri).path if uri else None


def parse_status_type(record):
    return record['status'] // 100 if 'status' in record else None


def to_int(value):
    return int(value) if value and value != '-' else 0


def to_float(value):
    return float(value) if value and value != '-' else 0.0


def parse_log(lines, pattern, time_rpl_expr=dict({'in_rpl_expr': r'.*', 'out_rpl_expr': r'.*'})):
    matches = (pattern.match(l) for l in lines)
    records = (m.groupdict() for m in matches if m is not None)
    records = map_field('status', to_int, records)
    records = add_field('status_type', parse_status_type, records)
    records = add_field('bytes_sent', lambda r: r['body_bytes_sent'], records)
    records = map_field('bytes_sent', to_int, records)
    records = map_field('request_time', to_float, records)
    records = add_field('request_path', parse_request_path, records)
    records = map_field('time_local',
                        lambda r: re.sub(time_rpl_expr['in_rpl_expr'], time_rpl_expr['out_rpl_expr'], fix_month(r)),
                        records)
    records = add_field('crc32_user_agent',
                        lambda r: "0x%08X" % (binascii.crc32(r['http_user_agent']) & 0xFFFFFFFF),
                        records)
    return records


# =================================
# Records and statistic processor
# =================================
class SQLProcessor(object):
    def __init__(self, report_queries, fields, auto_rotate, index_fields=None):
        self.begin = False
        self.report_queries = report_queries
        self.auto_rotate = auto_rotate
        self.index_fields = index_fields if index_fields is not None else []
        self.column_list = ','.join(fields.keys())
        self.column_list_ex = ','.join(['%s %s' % (key, value) for (key, value) in fields.items()])
        self.holder_list = ','.join(':%s' % var for var in fields.keys())
        self.conn = sqlite3.connect(':memory:')
        self.init_db()

    def process(self, records):
        self.begin = time.time()
        insert = 'insert into log (%s) values (%s)' % (self.column_list, self.holder_list)
        logging.info('sqlite insert: %s', insert)
        with closing(self.conn.cursor()) as cursor:
            for r in records:
                cursor.execute(insert, r)

    def report(self):
        if not self.begin:
            return ''
        if self.auto_rotate['enabled']:
            with closing(self.conn.cursor()) as cursor:
                cursor.execute(self.auto_rotate['get_last_ts_query'])
                self.auto_rotate['last_timestamp'] = cursor.fetchone()[0]
                if not self.auto_rotate['last_timestamp']:
                    self.auto_rotate['last_timestamp'] = dt.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                self.rotate()
        count = self.count()
        duration = time.time() - self.begin
        status = 'running for %.0f seconds, %d records processed: %.2f req/sec'
        output = [status % (duration, count, count / duration)]
        with closing(self.conn.cursor()) as cursor:
            for query in self.report_queries:
                if isinstance(query, tuple):
                    label, query = query
                else:
                    label = ''
                cursor.execute(query)
                columns = (d[0] for d in cursor.description)
                result = tabulate.tabulate(cursor.fetchall(), headers=columns, tablefmt='orgtbl', floatfmt='.3f')
                output.append('%s\n%s' % (label, result))
        return '\n\n'.join(output)

    def init_db(self):
        create_table = 'create table log (%s)' % self.column_list_ex
        with closing(self.conn.cursor()) as cursor:
            logging.info('sqlite init: %s', create_table)
            cursor.execute(create_table)
            for idx, field in enumerate(self.index_fields):
                sql = 'create index log_idx%d on log (%s)' % (idx, field)
                logging.info('sqlite init: %s', sql)
                cursor.execute(sql)

    def count(self):
        with closing(self.conn.cursor()) as cursor:
            cursor.execute('select count(1) from log')
            return cursor.fetchone()[0]

    def rotate(self):
        with closing(self.conn.cursor()) as cursor:
            cursor.execute(self.auto_rotate['delete_old_rows_query'], self.auto_rotate)


# ===============
# Log processing
# ===============
def process_log(lines, pattern, processor, arguments):
    time_rpl_expr = arguments['--time-rpl-expr']
    pre_filer_exp = arguments['--pre-filter']
    if pre_filer_exp:
        lines = (line for line in lines if eval(pre_filer_exp, {}, dict(line=line)))

    records = parse_log(lines, pattern, time_rpl_expr)

    filter_exp = arguments['--filter']
    if filter_exp:
        records = (r for r in records if eval(filter_exp, {}, r))

    processor.process(records)
    print(processor.report())  # this will only run when start in --no-follow mode


def build_processor(arguments):
    splitter = re.compile(DEFAULT_REGEXP_SPLITTER)

    group_by_list = arguments['--group-by']
    arguments['--list-group-by'] = list()
    arguments['--list-group-by-type'] = list()
    for arg in group_by_list.split(','):
        group_by_element = splitter.match(arg).groupdict()
        if group_by_element is None:
            error_exit('incorrect item group-by of fields data "%s"' % arg)
        arguments['--list-group-by'].append(group_by_element['key'])
        arguments['--list-group-by-type'].append(group_by_element['value'])
    arguments['--group-by'] = ','.join(arguments['--list-group-by'])
    arguments['--group-by-type'] = ','.join(arguments['--list-group-by-type'])

    fields = arguments['<var>']
    if arguments['print']:
        label = ', '.join(fields.keys()) + ':'
        selections = ', '.join(fields.keys())
        query = 'select %s from log group by %s' % (selections, selections)
        report_queries = [(label, query)]
    elif arguments['top']:
        limit = int(arguments['--limit'])
        report_queries = []
        for var in fields.keys():
            label = 'top %s' % var
            query = 'select %s, count(1) as count from log group by %s order by count desc limit %d' % (var, var, limit)
            report_queries.append((label, query))
    elif arguments['avg']:
        label = 'average %s' % fields.keys()
        selections = ', '.join('avg(%s)' % var for var in fields.keys())
        query = 'select %s from log' % selections
        report_queries = [(label, query)]
    elif arguments['sum']:
        label = 'sum %s' % fields.keys()
        selections = ', '.join('sum(%s)' % var for var in fields.keys())
        query = 'select %s from log' % selections
        report_queries = [(label, query)]
    elif arguments['query']:
        report_queries = arguments['<query>']
        fields = arguments['<fields>']
    else:
        report_queries = [(name, query % arguments) for name, query in DEFAULT_QUERIES]
        fields = dict(DEFAULT_FIELDS, **dict(zip(arguments['--list-group-by'], arguments['--list-group-by-type'])))

    for label, query in report_queries:
        logging.info('query for "%s":\n %s', label, query)

    auto_rotate = dict()
    limit_time = int(arguments['--auto-rotate'])
    auto_rotate['enabled'] = True if limit_time else False
    auto_rotate['interval'] = DEFAULT_LIMIT_TIME if limit_time < 0 or limit_time > 2592000 else limit_time
    auto_rotate['last_timestamp'] = ''
    if auto_rotate['enabled']:
        auto_rotate['get_last_ts_query'] = 'select max(time_local) from log'
        auto_rotate['delete_old_rows_query'] = 'delete from log where datetime(time_local) < ' \
                                               'datetime(:last_timestamp, "-" || :interval || " seconds")'
        logging.info('query for select last timestamp: %s', auto_rotate['get_last_ts_query'])
        logging.info('query for delete old rows: %s', auto_rotate['delete_old_rows_query'])

    if not arguments['--time-rpl-expr']:
        arguments['--time-rpl-expr'] = DEFAULT_REPLACE_EXPRESSION

    processor_fields = dict()
    if type(fields) is str:
        for field in fields:
            items = field.split(',')
            for item in items:
                fields_element = splitter.match(item).groupdict()
                if fields_element is None:
                    error_exit('failed parsing of field data "%s"' % item)
                processor_fields[fields_element['key']] = fields_element['value']
    elif type(fields) is dict:
        processor_fields = fields
    else:
        error_exit('incorrect type of fields data "%s"' % str(type(fields)))

    processor = SQLProcessor(report_queries, processor_fields, auto_rotate)
    return processor


def build_source(access_log, arguments):
    # constructing log source
    if access_log == 'stdin':
        lines = sys.stdin
    elif arguments['--no-follow']:
        lines = open(access_log)
    else:
        lines = follow(access_log)
    return lines


def setup_reporter(processor, arguments):
    if arguments['--no-follow']:
        return

    scr = curses.initscr()
    atexit.register(curses.endwin)

    def print_report(sig, frame):
        output = processor.report()
        scr.erase()
        try:
            scr.addstr(output)
        except curses.error:
            pass
        scr.refresh()

    signal.signal(signal.SIGALRM, print_report)
    interval = float(arguments['--interval'])
    signal.setitimer(signal.ITIMER_REAL, 0.1, interval)


def process(arguments):
    access_log = arguments['--access-log']
    log_format = arguments['--log-format']
    if access_log is None and not sys.stdin.isatty():
        # assume logs can be fetched directly from stdin when piped
        access_log = 'stdin'
    if access_log is None:
        access_log, log_format = detect_log_config(arguments)

    logging.info('access_log: %s', access_log)
    logging.info('log_format: %s', log_format)
    if access_log != 'stdin' and not os.path.exists(access_log):
        error_exit('access log file "%s" does not exist' % access_log)

    if arguments['info']:
        print('nginx configuration file:\n ', detect_config_path())
        print('access log file:\n ', access_log)
        print('access log format:\n ', log_format)
        print('available variables:\n ', ', '.join(sorted(extract_variables(log_format))))
        return

    source = build_source(access_log, arguments)
    pattern = build_pattern(log_format)
    processor = build_processor(arguments)
    setup_reporter(processor, arguments)
    process_log(source, pattern, processor, arguments)


def main():
    args = docopt(__doc__, version='xstat 0.1')

    log_level = logging.WARNING
    if args['--verbose']:
        log_level = logging.INFO
    if args['--debug']:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    logging.debug('arguments:\n%s', args)

    try:
        process(args)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
