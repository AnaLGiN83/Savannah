import unittest

import peewee
import redis
import tempfile
from app import config
from app.models import User, Alert, Stat
from peewee import SqliteDatabase
from app.config import REDIS_HOST, REDIS_PORT


class with_test_db:
    def __init__(self, dbs: tuple):
        self.dbs = dbs

    def __call__(self, cls):
        def run(innerself, *args, **kwargs):
            test_db = SqliteDatabase(":memory:")
            with test_db.bind_ctx(self.dbs):
                test_db.create_tables(self.dbs)
                try:
                    cls.run(innerself, *args, **kwargs)
                finally:
                    test_db.drop_tables(self.dbs)
                    test_db.close()

        return type(cls.__name__, (cls,), {"run": run})


@with_test_db((User,))
class UserTestCase(unittest.TestCase):
    def create_test_user(self):
        user = User(username='test')
        user.set_password('test')
        user.name = 'Test'
        user.is_admin = False
        return user.save()

    def test_user_create(self):
        self.assertEqual(self.create_test_user(), 1)

    def test_user_get(self):
        self.create_test_user()
        user = User.get(username='test')
        self.assertEqual(user.username, 'test')
        self.assertEqual(user.name, 'Test')
        self.assertTrue(User.check_password(user, 'test'))

    def test_user_delete(self):
        self.create_test_user()
        user = User.get(username='test')
        self.assertEqual(user.delete_instance(), 1)

    def test_username_unique(self):
        self.create_test_user()
        try:
            self.create_test_user()
        except peewee.IntegrityError:
            pass
        else:
            self.assertFalse(True)

    def test_password_unique(self):
        self.create_test_user()
        user2 = User(username='test2', is_admin=True)
        user2.set_password('test')
        self.assertEqual(user2.save(), 1)


class AlertTestCase(unittest.TestCase):
    test_alerts = [
        '{"timestamp":"2022-05-23T21:01:11.954578+0300","flow_id":481121362481859,"in_iface":"enp0s3","event_type":"alert","src_ip":"10.0.2.15","src_port":35756,"dest_ip":"104.16.249.249","dest_port":443,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":2027695,"rev":4,"signature":"ET INFO Observed Cloudflare DNS over HTTPS Domain (cloudflare-dns .com in TLS SNI)","category":"Misc activity","severity":3,"metadata":{"affected_product":["Any"],"attack_target":["Client_Endpoint"],"created_at":["2019_07_09"],"deployment":["Perimeter"],"former_category":["POLICY"],"performance_impact":["Low"],"signature_severity":["Informational"],"tag":["DoH"],"updated_at":["2020_09_17"]}},"tls":{"sni":"mozilla.cloudflare-dns.com","version":"TLS 1.3","ja3":{"hash":"579ccef312d18482fc42e2b822ca2430","string":"771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0"},"ja3s":{"hash":"eb1d94daa7e0344597e756a1fb6e7054","string":"771,4865,51-43"}},"app_proto":"tls","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":753,"bytes_toclient":1634,"start":"2022-05-23T21:01:11.889539+0300"}}',
        '{"timestamp":"2022-05-23T18:20:24.325003+0300","flow_id":1918281211993271,"in_iface":"enp0s3","event_type":"alert","src_ip":"10.0.2.15","src_port":35746,"dest_ip":"104.16.249.249","dest_port":443,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":2027695,"rev":4,"signature":"ET INFO Observed Cloudflare DNS over HTTPS Domain (cloudflare-dns .com in TLS SNI)","category":"Misc activity","severity":3,"metadata":{"affected_product":["Any"],"attack_target":["Client_Endpoint"],"created_at":["2019_07_09"],"deployment":["Perimeter"],"former_category":["POLICY"],"performance_impact":["Low"],"signature_severity":["Informational"],"tag":["DoH"],"updated_at":["2020_09_17"]}},"tls":{"sni":"mozilla.cloudflare-dns.com","version":"TLS 1.3","ja3":{"hash":"579ccef312d18482fc42e2b822ca2430","string":"771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0"},"ja3s":{"hash":"eb1d94daa7e0344597e756a1fb6e7054","string":"771,4865,51-43"}},"app_proto":"tls","flow":{"pkts_toserver":4,"pkts_toclient":4,"bytes_toserver":753,"bytes_toclient":3148,"start":"2022-05-23T18:20:24.285879+0300"}}'
    ]

    def setUp(self):
        Alert.database = redis.StrictRedis(REDIS_HOST, REDIS_PORT)
        Alert.database.lpush('test_alerts', self.test_alerts)
        Alert.list_name = 'test_alerts'

    def tearDown(self):
        if Alert.database.get('test_alerts'):
            Alert.database.delete('test_alerts')

    def test_data_normal(self):
        self.assertEqual(Alert.count(), 2)

    def test_get(self):
        self.assertEqual(Alert.parse_from_eve(self.test_alerts[0]), Alert.get_by_id(0))

    def test_get_range(self):
        processed = []
        for line in self.test_alerts:
            processed.append(Alert.parse_from_eve(line))
        self.assertEqual(processed, Alert.get_range(0, 2))


class StatTestCase(unittest.TestCase):
    test_stats = [
        '{"timestamp":"2022-05-22T00:00:24.329299+0300","event_type":"stats","stats":{"uptime":436644,"capture":{"kernel_packets":310840,"kernel_drops":2403,"errors":0},"decoder":{"pkts":308437,"bytes":215106708,"invalid":0,"ipv4":296356,"ipv6":877,"ethernet":308437,"chdlc":0,"raw":0,"null":0,"sll":0,"tcp":284292,"udp":12186,"sctp":0,"icmpv4":0,"icmpv6":752,"ppp":0,"pppoe":0,"geneve":0,"gre":0,"vlan":0,"vlan_qinq":0,"vxlan":0,"vntag":0,"ieee8021ah":0,"teredo":0,"ipv4_in_ipv6":0,"ipv6_in_ipv6":0,"mpls":0,"avg_pkt_size":697,"max_pkt_size":1514,"max_mac_addrs_src":0,"max_mac_addrs_dst":0,"erspan":0,"event":{"ipv4":{"pkt_too_small":0,"hlen_too_small":0,"iplen_smaller_than_hlen":0,"trunc_pkt":0,"opt_invalid":0,"opt_invalid_len":0,"opt_malformed":0,"opt_pad_required":3,"opt_eol_required":0,"opt_duplicate":0,"opt_unknown":0,"wrong_ip_version":0,"icmpv6":0,"frag_pkt_too_large":0,"frag_overlap":0,"frag_ignored":0},"icmpv4":{"pkt_too_small":0,"unknown_type":0,"unknown_code":0,"ipv4_trunc_pkt":0,"ipv4_unknown_ver":0},"icmpv6":{"unknown_type":0,"unknown_code":0,"pkt_too_small":0,"ipv6_unknown_version":0,"ipv6_trunc_pkt":0,"mld_message_with_invalid_hl":0,"unassigned_type":0,"experimentation_type":0},"ipv6":{"pkt_too_small":0,"trunc_pkt":0,"trunc_exthdr":0,"exthdr_dupl_fh":0,"exthdr_useless_fh":0,"exthdr_dupl_rh":0,"exthdr_dupl_hh":0,"exthdr_dupl_dh":0,"exthdr_dupl_ah":0,"exthdr_dupl_eh":0,"exthdr_invalid_optlen":0,"wrong_ip_version":0,"exthdr_ah_res_not_null":0,"hopopts_unknown_opt":0,"hopopts_only_padding":0,"dstopts_unknown_opt":0,"dstopts_only_padding":0,"rh_type_0":0,"zero_len_padn":631,"fh_non_zero_reserved_field":0,"data_after_none_header":0,"unknown_next_header":0,"icmpv4":0,"frag_pkt_too_large":0,"frag_overlap":0,"frag_invalid_length":0,"frag_ignored":0,"ipv4_in_ipv6_too_small":0,"ipv4_in_ipv6_wrong_version":0,"ipv6_in_ipv6_too_small":0,"ipv6_in_ipv6_wrong_version":0},"tcp":{"pkt_too_small":0,"hlen_too_small":0,"invalid_optlen":0,"opt_invalid_len":0,"opt_duplicate":0},"udp":{"pkt_too_small":0,"hlen_too_small":0,"hlen_invalid":0},"sll":{"pkt_too_small":0},"ethernet":{"pkt_too_small":0},"ppp":{"pkt_too_small":0,"vju_pkt_too_small":0,"ip4_pkt_too_small":0,"ip6_pkt_too_small":0,"wrong_type":0,"unsup_proto":0},"pppoe":{"pkt_too_small":0,"wrong_code":0,"malformed_tags":0},"gre":{"pkt_too_small":0,"wrong_version":0,"version0_recur":0,"version0_flags":0,"version0_hdr_too_big":0,"version0_malformed_sre_hdr":0,"version1_chksum":0,"version1_route":0,"version1_ssr":0,"version1_recur":0,"version1_flags":0,"version1_no_key":0,"version1_wrong_protocol":0,"version1_malformed_sre_hdr":0,"version1_hdr_too_big":0},"vlan":{"header_too_small":0,"unknown_type":0,"too_many_layers":0},"ieee8021ah":{"header_too_small":0},"vntag":{"header_too_small":0,"unknown_type":0},"ipraw":{"invalid_ip_version":0},"ltnull":{"pkt_too_small":0,"unsupported_type":0},"sctp":{"pkt_too_small":0},"mpls":{"header_too_small":0,"pkt_too_small":0,"bad_label_router_alert":0,"bad_label_implicit_null":0,"bad_label_reserved":0,"unknown_payload_type":0},"vxlan":{"unknown_payload_type":0},"geneve":{"unknown_payload_type":0},"erspan":{"header_too_small":0,"unsupported_version":0,"too_many_vlan_layers":0},"dce":{"pkt_too_small":0},"chdlc":{"pkt_too_small":0}},"too_many_layers":0},"flow":{"memcap":0,"tcp":4276,"udp":6068,"icmpv4":0,"icmpv6":300,"tcp_reuse":0,"get_used":0,"get_used_eval":0,"get_used_eval_reject":0,"get_used_eval_busy":0,"get_used_failed":0,"wrk":{"spare_sync_avg":100,"spare_sync":94,"spare_sync_incomplete":0,"spare_sync_empty":0,"flows_evicted_needs_work":1286,"flows_evicted_pkt_inject":1365,"flows_evicted":56,"flows_injected":1285},"mgr":{"full_hash_pass":1820,"closed_pruned":0,"new_pruned":0,"est_pruned":0,"bypassed_pruned":0,"rows_maxlen":2,"flows_checked":19440,"flows_notimeout":8862,"flows_timeout":10578,"flows_timeout_inuse":0,"flows_evicted":10578,"flows_evicted_needs_work":1285},"spare":10992,"emerg_mode_entered":0,"emerg_mode_over":0,"memuse":7834776},"defrag":{"ipv4":{"fragments":0,"reassembled":0,"timeouts":0},"ipv6":{"fragments":0,"reassembled":0,"timeouts":0},"max_frag_hits":0},"flow_bypassed":{"local_pkts":0,"local_bytes":0,"local_capture_pkts":0,"local_capture_bytes":0,"closed":0,"pkts":0,"bytes":0},"tcp":{"sessions":3967,"ssn_memcap_drop":0,"pseudo":0,"pseudo_failed":0,"invalid_checksum":0,"no_flow":0,"syn":4985,"synack":2812,"rst":2100,"midstream_pickups":0,"pkt_on_wrong_thread":0,"segment_memcap_drop":0,"stream_depth_reached":18,"reassembly_gap":0,"overlap":15,"overlap_diff_data":0,"insert_data_normal_fail":0,"insert_data_overlap_fail":0,"insert_list_fail":0,"memuse":606208,"reassembly_memuse":435280},"detect":{"engines":[{"id":0,"last_reload":"2022-05-16T22:43:37.453113+0300","rules_loaded":25983,"rules_failed":0}],"alert":168},"app_layer":{"flow":{"http":1498,"ftp":0,"smtp":0,"tls":1217,"ssh":0,"imap":0,"smb":0,"dcerpc_tcp":0,"dns_tcp":0,"nfs_tcp":0,"ntp":213,"ftp-data":0,"tftp":0,"ikev2":0,"krb5_tcp":0,"dhcp":10,"snmp":0,"sip":0,"rfb":0,"mqtt":0,"rdp":0,"failed_tcp":5,"dcerpc_udp":0,"dns_udp":5576,"nfs_udp":0,"krb5_udp":0,"failed_udp":269},"tx":{"http":1697,"ftp":0,"smtp":0,"tls":0,"ssh":0,"imap":0,"smb":0,"dcerpc_tcp":0,"dns_tcp":0,"nfs_tcp":0,"ntp":226,"ftp-data":0,"tftp":0,"ikev2":0,"krb5_tcp":0,"dhcp":20,"snmp":0,"sip":0,"rfb":0,"mqtt":0,"rdp":0,"dcerpc_udp":0,"dns_udp":11207,"nfs_udp":0,"krb5_udp":0},"expectations":0},"http":{"memuse":96,"memcap":0},"ftp":{"memuse":0,"memcap":0},"file_store":{"open_files":0}}}',
        '{"timestamp":"2022-05-22T00:27:04.534121+0300","event_type":"stats","stats":{"uptime":438244,"capture":{"kernel_packets":311414,"kernel_drops":2403,"errors":0},"decoder":{"pkts":309011,"bytes":215189910,"invalid":0,"ipv4":296885,"ipv6":882,"ethernet":309011,"chdlc":0,"raw":0,"null":0,"sll":0,"tcp":284785,"udp":12222,"sctp":0,"icmpv4":0,"icmpv6":757,"ppp":0,"pppoe":0,"geneve":0,"gre":0,"vlan":0,"vlan_qinq":0,"vxlan":0,"vntag":0,"ieee8021ah":0,"teredo":0,"ipv4_in_ipv6":0,"ipv6_in_ipv6":0,"mpls":0,"avg_pkt_size":696,"max_pkt_size":1514,"max_mac_addrs_src":0,"max_mac_addrs_dst":0,"erspan":0,"event":{"ipv4":{"pkt_too_small":0,"hlen_too_small":0,"iplen_smaller_than_hlen":0,"trunc_pkt":0,"opt_invalid":0,"opt_invalid_len":0,"opt_malformed":0,"opt_pad_required":3,"opt_eol_required":0,"opt_duplicate":0,"opt_unknown":0,"wrong_ip_version":0,"icmpv6":0,"frag_pkt_too_large":0,"frag_overlap":0,"frag_ignored":0},"icmpv4":{"pkt_too_small":0,"unknown_type":0,"unknown_code":0,"ipv4_trunc_pkt":0,"ipv4_unknown_ver":0},"icmpv6":{"unknown_type":0,"unknown_code":0,"pkt_too_small":0,"ipv6_unknown_version":0,"ipv6_trunc_pkt":0,"mld_message_with_invalid_hl":0,"unassigned_type":0,"experimentation_type":0},"ipv6":{"pkt_too_small":0,"trunc_pkt":0,"trunc_exthdr":0,"exthdr_dupl_fh":0,"exthdr_useless_fh":0,"exthdr_dupl_rh":0,"exthdr_dupl_hh":0,"exthdr_dupl_dh":0,"exthdr_dupl_ah":0,"exthdr_dupl_eh":0,"exthdr_invalid_optlen":0,"wrong_ip_version":0,"exthdr_ah_res_not_null":0,"hopopts_unknown_opt":0,"hopopts_only_padding":0,"dstopts_unknown_opt":0,"dstopts_only_padding":0,"rh_type_0":0,"zero_len_padn":635,"fh_non_zero_reserved_field":0,"data_after_none_header":0,"unknown_next_header":0,"icmpv4":0,"frag_pkt_too_large":0,"frag_overlap":0,"frag_invalid_length":0,"frag_ignored":0,"ipv4_in_ipv6_too_small":0,"ipv4_in_ipv6_wrong_version":0,"ipv6_in_ipv6_too_small":0,"ipv6_in_ipv6_wrong_version":0},"tcp":{"pkt_too_small":0,"hlen_too_small":0,"invalid_optlen":0,"opt_invalid_len":0,"opt_duplicate":0},"udp":{"pkt_too_small":0,"hlen_too_small":0,"hlen_invalid":0},"sll":{"pkt_too_small":0},"ethernet":{"pkt_too_small":0},"ppp":{"pkt_too_small":0,"vju_pkt_too_small":0,"ip4_pkt_too_small":0,"ip6_pkt_too_small":0,"wrong_type":0,"unsup_proto":0},"pppoe":{"pkt_too_small":0,"wrong_code":0,"malformed_tags":0},"gre":{"pkt_too_small":0,"wrong_version":0,"version0_recur":0,"version0_flags":0,"version0_hdr_too_big":0,"version0_malformed_sre_hdr":0,"version1_chksum":0,"version1_route":0,"version1_ssr":0,"version1_recur":0,"version1_flags":0,"version1_no_key":0,"version1_wrong_protocol":0,"version1_malformed_sre_hdr":0,"version1_hdr_too_big":0},"vlan":{"header_too_small":0,"unknown_type":0,"too_many_layers":0},"ieee8021ah":{"header_too_small":0},"vntag":{"header_too_small":0,"unknown_type":0},"ipraw":{"invalid_ip_version":0},"ltnull":{"pkt_too_small":0,"unsupported_type":0},"sctp":{"pkt_too_small":0},"mpls":{"header_too_small":0,"pkt_too_small":0,"bad_label_router_alert":0,"bad_label_implicit_null":0,"bad_label_reserved":0,"unknown_payload_type":0},"vxlan":{"unknown_payload_type":0},"geneve":{"unknown_payload_type":0},"erspan":{"header_too_small":0,"unsupported_version":0,"too_many_vlan_layers":0},"dce":{"pkt_too_small":0},"chdlc":{"pkt_too_small":0}},"too_many_layers":0},"flow":{"memcap":0,"tcp":4288,"udp":6086,"icmpv4":0,"icmpv6":302,"tcp_reuse":0,"get_used":0,"get_used_eval":0,"get_used_eval_reject":0,"get_used_eval_busy":0,"get_used_failed":0,"wrk":{"spare_sync_avg":100,"spare_sync":94,"spare_sync_incomplete":0,"spare_sync_empty":0,"flows_evicted_needs_work":1291,"flows_evicted_pkt_inject":1370,"flows_evicted":56,"flows_injected":1290},"mgr":{"full_hash_pass":1826,"closed_pruned":0,"new_pruned":0,"est_pruned":0,"bypassed_pruned":0,"rows_maxlen":2,"flows_checked":19504,"flows_notimeout":8892,"flows_timeout":10612,"flows_timeout_inuse":0,"flows_evicted":10612,"flows_evicted_needs_work":1290},"spare":11021,"emerg_mode_entered":0,"emerg_mode_over":0,"memuse":7834776},"defrag":{"ipv4":{"fragments":0,"reassembled":0,"timeouts":0},"ipv6":{"fragments":0,"reassembled":0,"timeouts":0},"max_frag_hits":0},"flow_bypassed":{"local_pkts":0,"local_bytes":0,"local_capture_pkts":0,"local_capture_bytes":0,"closed":0,"pkts":0,"bytes":0},"tcp":{"sessions":3979,"ssn_memcap_drop":0,"pseudo":0,"pseudo_failed":0,"invalid_checksum":0,"no_flow":0,"syn":5007,"synack":2823,"rst":2100,"midstream_pickups":0,"pkt_on_wrong_thread":0,"segment_memcap_drop":0,"stream_depth_reached":18,"reassembly_gap":0,"overlap":15,"overlap_diff_data":0,"insert_data_normal_fail":0,"insert_data_overlap_fail":0,"insert_list_fail":0,"memuse":606208,"reassembly_memuse":321904},"detect":{"engines":[{"id":0,"last_reload":"2022-05-16T22:43:37.453113+0300","rules_loaded":25983,"rules_failed":0}],"alert":169},"app_layer":{"flow":{"http":1503,"ftp":0,"smtp":0,"tls":1223,"ssh":0,"imap":0,"smb":0,"dcerpc_tcp":0,"dns_tcp":0,"nfs_tcp":0,"ntp":214,"ftp-data":0,"tftp":0,"ikev2":0,"krb5_tcp":0,"dhcp":10,"snmp":0,"sip":0,"rfb":0,"mqtt":0,"rdp":0,"failed_tcp":5,"dcerpc_udp":0,"dns_udp":5593,"nfs_udp":0,"krb5_udp":0,"failed_udp":269},"tx":{"http":1702,"ftp":0,"smtp":0,"tls":0,"ssh":0,"imap":0,"smb":0,"dcerpc_tcp":0,"dns_tcp":0,"nfs_tcp":0,"ntp":227,"ftp-data":0,"tftp":0,"ikev2":0,"krb5_tcp":0,"dhcp":20,"snmp":0,"sip":0,"rfb":0,"mqtt":0,"rdp":0,"dcerpc_udp":0,"dns_udp":11241,"nfs_udp":0,"krb5_udp":0},"expectations":0},"http":{"memuse":96,"memcap":0},"ftp":{"memuse":0,"memcap":0},"file_store":{"open_files":0}}}'
    ]

    def setUp(self):
        Stat.database = redis.StrictRedis(REDIS_HOST, REDIS_PORT)
        Stat.database.lpush('test_stats', self.test_stats)
        Stat.list_name = 'test_stats'

    def tearDown(self):
        if Stat.database.get('test_stats'):
            Stat.database.delete('test_stats')

    def test_data_normal(self):
        self.assertEqual(Stat.count(), 2)

    def test_get(self):
        self.assertEqual(Stat.parse_from_eve(self.test_stats[0]), Stat.get_by_id(0))

    def test_get_range(self):
        processed = []
        for line in self.test_stats:
            processed.append(Stat.parse_from_eve(line))
        self.assertEqual(processed, Stat.get_range(0, 2))

if __name__ == '__main__':
    unittest.main()
