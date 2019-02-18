#!/usr/bin/python
import os
import json
from argparse import ArgumentParser
from kitty.data.data_manager import DataManager


def parse_args():
    parser = ArgumentParser(description='Checker')
    parser.add_argument('-p', dest='session_path', required=True, help='Path to sessions')
    parser.add_argument('-i', dest='id', help='Report id for show')
    return parser.parse_args()


def decode(r):
    res = r._data_fields
    for sub in r._data_fields['sub_reports']:
        res[sub] = decode(r._sub_reports[sub])
    return res


def get_status(r):
    report_status = '%s ' % r['status']
    for sub in r['sub_reports']:
        report_status += '%s:%s ' % (sub, get_status(r[sub]))
    return report_status.strip()


def show_report_by_id(session, test_id):
    dataman = DataManager(session)
    dataman.open()
    r = decode(dataman._reports.get(test_id))
    print(r)


def main():
    args = parse_args()
    if args.id:
        show_report_by_id(args.session_path, args.id)
    else:
        files = os.listdir(args.session_path)
        for session in filter(lambda x: x.endswith('.sqlite'), files):
            dataman = DataManager(session)
            dataman.open()
            for test_id, status, reason in dataman._reports.get_report_list():
                r = decode(dataman._reports.get(test_id))
                report_status = get_status(r)
                print('%s id: %d status: %s reason: %s (%s)' % (
                    session, test_id, status, reason, report_status
                ))


if __name__ == '__main__':
    main()
