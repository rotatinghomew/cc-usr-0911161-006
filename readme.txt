跨境人工智能数据合作许可登记库

运行验收：
python3 -m data_permit run --fixture fixtures/acceptance.json --database /tmp/data_permit.sqlite3 --output /tmp/data_permit-output

核验：
python3 -m data_permit verify --database /tmp/data_permit.sqlite3 --output /tmp/data_permit-output

全量测试：
python3 -m unittest discover -s tests -v

按模块测试：
python3 -m unittest tests.permit_signal.test_permit_risk -v

构建检查：
python3 -m compileall -q data_permit tests
