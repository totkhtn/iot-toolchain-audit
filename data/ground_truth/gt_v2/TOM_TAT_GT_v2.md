# Ground truth v2 (2140 tệp, 605021 hàm)

| Vai trò chi tiết | Số hàm |
|---|---|
| thu_vien | 459564 |
| tac_gia | 59844 |
| payload | 55623 |
| helper | 29990 |

Lý do xếp thư viện / tác giả (chỉ hàm không phải payload/helper v1):

- ten_libc: 257761
- gach_duoi: 179220
- con_lai: 59844
- ten_chung_10pct: 21982
- bam_thu_vien: 601

Tên `tac_gia` phổ biến nhất (rà tay — nếu thấy tên libc thì bổ sung vào danh sách libc):

main (2133), parse_request (208), httpd_serve (208), httpd_start (208), update_bins (208), cleanup (205), read_until_response (204), ensure_bind (202), skip_nospace (202), skip_and_NUL_space (202), findRandIP (201), send_udp_packets (199), zprintf (195), wildString (191), thread_self (190), sclose (187), check_list.7052 (186), rtcp (179), SendUDP (171), audp (168), atcp (168), contains_string (157), read_with_timeout (155), SendSTDHEX (148), kill_malware (144), ioctl_keepalive (140), lock_commands (140), get_telstate_host (138), reset_telstate (138), SendHTTPHex (136), getEndianness (134), getPortz (132), local_addr (132), contains_fail (131), contains_success (129), contains_response (129), cancel_handler (122), do_system (121), parse_elf_response (118), kutil_strcpy (117), kutil_memsearch (117), kutil_strlen (117), add_combo (117), kutil_memcpy (113), kutil_memmove (113), kutil_memset (113), kutil_strcat (112), kutil_strcmp (112), kutil_strncmp (112), kutil_read (112), kutil_strdup (112), read_cmdline_path (111), SendHTTP (109), real_init (109), UpdateNameSrvs (106), parseHex (105), sendHTTPtwo (103), get_retrieve_binary (98), process_retrieve_binary (98), ftcp (97)
