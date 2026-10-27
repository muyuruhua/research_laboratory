消融项：direct,gated_fixed,calibrated,cal_gamma099,cal_gamma100

cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && ./run_ablation.sh bftpd 1 1540 -g direct,gated_fixed,calibrated,cal_gamma099,cal_gamma100

cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && ./run_ablation.sh pure-ftpd 1 1540 -g direct,gated_fixed,calibrated,cal_gamma099,cal_gamma100

cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && ./run_ablation.sh live555 1 1540 -g direct,gated_fixed,calibrated,cal_gamma099,cal_gamma100



cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && ./run_ablation.sh exim 1 1540 -g direct,gated_fixed,calibrated,cal_gamma099,cal_gamma100 

cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && ./run_ablation.sh lighttpd1 1 1540 -g direct,gated_fixed,calibrated,cal_gamma099,cal_gamma100 

cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && ./run_ablation.sh kamailio 1 1540 -g direct,gated_fixed,calibrated,cal_gamma099,cal_gamma100 




cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && ./run_ablation.sh forked-daapd 1 1540 -g direct,gated_fixed,calibrated,cal_gamma099,cal_gamma100

cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && ./run_ablation.sh proftpd 1 1540 -g direct,gated_fixed,calibrated,cal_gamma099,cal_gamma100

cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && ./run_ablation.sh lightftp 1 1540 -g direct,gated_fixed,calibrated,cal_gamma099,cal_gamma100 





no-LLM 臂（免费，KEY 可省）
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export SKIPCOUNT=100 && CHATAFL_NO_LLM=1 ./run_dev.sh 5 1540 bftpd,exim,live555,kamailio,lighttpd1,forked-daapd,lightftp,proftpd,pure-ftpd loopfuzz



code_retain 臂（D+保留策略）
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && CHATAFL_CODE_RETAIN=1 ./run_dev.sh 2 1540 bftpd,exim,live555,kamailio,lighttpd1,forked-daapd,lightftp,proftpd,pure-ftpd loopfuzz



random_state 臂（可选缓跑）
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && CHATAFL_STATE_SELECT=random ./run_dev.sh 2 1540 bftpd,exim,live555,kamailio,lighttpd1,forked-daapd,lightftp,proftpd,pure-ftpd loopfuzz



cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/loopfuzz && python3 llm_mock_v4.py

cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && KEY=mock-key CHATAFL_LLM_BASE=http://172.17.0.1:8099/v1/chat/completions CHATAFL_ADMISSION_MODE=gate CHATAFL_PROVISIONAL=1 CHATAFL_SHADOW=1 ./run_dev.sh 1 60 lightftp loopfuzz

cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && KEY=mock-key CHATAFL_LLM_BASE=http://172.17.0.1:8099/v1/chat/completions ./run_ablation.sh lightftp 1 1540 --groups direct,native,gate,gate_only,calibrated,cal_ewma


# 新格式：./run_ablation.sh <runs> <minutes> <target> custom <arms>
# 旧格式：./run_ablation.sh <target> <runs> <minutes> -g <groups>  [已弃用]

# 最小实验（6 臂，回答全部关键问题）
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && \
export KEY="sk-你的密钥" && \
export SKIPCOUNT=100 && \
export CHATAFL_MAX_TOKENS=4096 && \
export CHATAFL_LLM_TIMEOUT_MS=300000 && \
ABLATION_SHUFFLE=1 ./run_ablation.sh 1 1540 lightftp custom direct,native,gate_only,gate,calibrated,cal_ewma

# 全量实验（11 臂）
ABLATION_SHUFFLE=1 ./run_ablation.sh 1 1540 lightftp custom \
  direct,native,gate_only,gate_prov,gate,calibrated,cal_ewma,cal_run_rate,code_retain,cal_gamma099,cal_gamma100




cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && ABLATION_SHUFFLE=1 && export LLM_MODEL=gpt-6-astra &&./run_ablation.sh proftpd 1 1540 --groups direct,native,gate_only,gate_prov,gate,calibrated,cal_ewma,cal_run_rate,code_retain,cal_gamma099,cal_gamma100


cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && ABLATION_SHUFFLE=1 && export LLM_MODEL=gpt-6-astra &&./run_ablation.sh proftpd 1 1540 --groups direct, native, gate_only, gate, calibrated, cal_ewma

