跨境人工智能数据合作许可登记库

运行验收：
python3 -m data_permit run --fixture fixtures/acceptance.json --database /tmp/data_permit.sqlite3 --output /tmp/data_permit-output

核验：
python3 -m data_permit verify --database /tmp/data_permit.sqlite3 --output /tmp/data_permit-output

查看当前记录、决定与分层分析：
python3 -m data_permit inspect --database /tmp/data_permit.sqlite3

全量测试：
python3 -m unittest discover -s tests -v

按模块测试：
python3 -m unittest tests.permit_signal.test_permit_risk -v
python3 -m unittest tests.domain.test_stratified_analysis -v

构建检查：
python3 -m compileall -q data_permit tests

分层分析说明：
- 分析单元为 data_space × subject_group × classification_version；三者任一缺失的记录进入
  unassigned_records，不做猜测归并。
- 分析总体仅含 authorization_scope 授权 validation 用途的记录；未授权记录计入
  分母说明中的 excluded_record_ids，不进入任何分子或分母。
- 保护效果分母为敏感阳性例数 sum(sample_size * sensitive_share)，缺失率分母为
  validation 授权样本量 sum(sample_size)，均给出 Wilson 95% 区间。
- 无 validation 授权、validation 样本不足（<30）或缺少阳性分母的分组不可排名，
  rank 为 null 并给出原因；只有在同一群体与分类版本内、区间彼此分离时才给出序数名次。
- 同一分析对象（basis hash）同时供审查决定与 stratified-analysis.json / summary.json /
  decisions.json 引用，verify 会核对决定所引用的分析确实已入库。
- 内容相同的重复提交不新增版本或决定；记录更正或分析依据变化时写入新的决定，
  以 supersedes 指向旧决定，旧决定保留不被改写。
