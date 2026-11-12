# RQ1 grouped (10 seed, test, GT v2); tệp test GT tổng = 2763

Tỉ trọng (mean qua seed của mean theo tệp): payload+tác giả 0.157±0.070, helper 0.110±0.082, thư viện 0.733±0.124

| Điểm | AUC | AP | Hit@5 |
|---|---|---|---|
| s_topk | 0.510±0.025 | 0.461±0.026 | 0.586±0.243 |
| s_sum | 0.409±0.061 | 0.162±0.033 | 0.282±0.222 |
| s_max | 0.407±0.062 | 0.171±0.023 | 0.544±0.290 |
| b_ninsn | 0.745±0.037 | 0.399±0.067 | 0.992±0.018 |
| b_nblocks | 0.614±0.008 | 0.255±0.040 | 0.840±0.099 |
| b_nsys | 0.330±0.008 | 0.175±0.020 | 0.049±0.046 |
| b_random | 0.505±0.003 | 0.167±0.023 | 0.541±0.061 |

| Hàm | vai trò | tỉ trọng gộp |
|---|---|---|
| malloc | thu_vien | 13.2% |
| _start | thu_vien | 6.5% |
| __udivsi3 | thu_vien | 5.3% |
| realloc | thu_vien | 5.1% |
| attack_start | payload | 5.1% |
| util_atoi | helper | 4.7% |
| checksum_tcpudp | helper | 4.2% |
| __divsi3 | thu_vien | 3.4% |
| __GI_config_read | thu_vien | 3.2% |
| main | tac_gia | 3.1% |
| __stdio_READ | thu_vien | 2.7% |
| scanner_init | payload | 2.5% |
| __do_global_dtors_aux | thu_vien | 2.5% |
| free | thu_vien | 2.3% |
| resolv_lookup | payload | 2.2% |
