# scan_data = your_discovery_agent.run(host="xxx")[0]['scan_data']

# # 2. Generate improved signature
# from binary_matcher import HighPerformanceBinaryMatcher
# signature = HighPerformanceBinaryMatcher.generate_scan_signatures(
#     scan_data['nmap'], 
#     scan_data['probes']
# )

# # 3. Insert/update in database
# from core.database import get_db_session
# from sqlalchemy import text

# with get_db_session() as session:
#     session.execute(text("""
#         UPDATE protocol_signatures 
#         SET port_signature = :port_sig,
#             banner_signature = :banner_sig,
#             endpoint_signature = :endpoint_sig,
#             keyword_signature = :keyword_sig,
#             uniqueness_score = 0.8,
#             signature_version = signature_version + 1
#         WHERE protocol_id = (SELECT id FROM protocols WHERE name = 'sui')
#     """), {
#         'port_sig': signature['port'],
#         'banner_sig': signature['banner'], 
#         'endpoint_sig': signature['endpoint'],
#         'keyword_sig': signatureRetryClaude can make mistakes. Please double-check responses.