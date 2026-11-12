# RQ1 grouped (10 seeds, test files, GT v2); total GT test files = 2763

Evidence shares (mean over seeds of the per-file mean): payload+author 0.157±0.070, helper 0.110±0.082, library 0.733±0.124

| Score | AUC | AP | Hit@5 |
|---|---|---|---|
| s_topk | 0.510±0.025 | 0.461±0.026 | 0.586±0.243 |
| s_sum | 0.409±0.061 | 0.162±0.033 | 0.282±0.222 |
| s_max | 0.407±0.062 | 0.171±0.023 | 0.544±0.290 |
| b_ninsn | 0.745±0.037 | 0.399±0.067 | 0.992±0.018 |
| b_nblocks | 0.614±0.008 | 0.255±0.040 | 0.840±0.099 |
| b_nsys | 0.330±0.008 | 0.175±0.020 | 0.049±0.046 |
| b_random | 0.505±0.003 | 0.167±0.023 | 0.541±0.061 |

| Function | Role | Pooled share |
|---|---|---|
| malloc | library | 13.2% |
| _start | library | 6.5% |
| __udivsi3 | library | 5.3% |
| realloc | library | 5.1% |
| attack_start | payload | 5.1% |
| util_atoi | helper | 4.7% |
| checksum_tcpudp | helper | 4.2% |
| __divsi3 | library | 3.4% |
| __GI_config_read | library | 3.2% |
| main | author | 3.1% |
| __stdio_READ | library | 2.7% |
| scanner_init | payload | 2.5% |
| __do_global_dtors_aux | library | 2.5% |
| free | library | 2.3% |
| resolv_lookup | payload | 2.2% |
