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

















