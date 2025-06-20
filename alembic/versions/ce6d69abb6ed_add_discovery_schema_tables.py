"""add_discovery_schema_tables

Revision ID: ce6d69abb6ed
Revises: bce123290ff7
Create Date: 2025-06-20 12:06:52.582723

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ce6d69abb6ed'
down_revision: Union[str, Sequence[str], None] = 'bce123290ff7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create scan_sessions table
    op.create_table('scan_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('total_hosts', sa.Integer(), nullable=False),
        sa.Column('successful_detections', sa.Integer(), nullable=False),
        sa.Column('failed_scans', sa.Integer(), nullable=False),
        sa.Column('scanner_version', sa.String(length=20), nullable=True),
        sa.Column('config_hash', sa.String(length=64), nullable=True),
        sa.Column('created_by', sa.String(length=100), nullable=True),
        sa.Column('notes', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_id')
    )
    
    # Create host_discoveries table
    op.create_table('host_discoveries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('detected_protocol', sa.String(length=100), nullable=True),
        sa.Column('confidence_level', sa.String(length=20), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('detection_method', sa.String(length=100), nullable=True),
        sa.Column('scan_started_at', sa.DateTime(), nullable=False),
        sa.Column('scan_completed_at', sa.DateTime(), nullable=True),
        sa.Column('scan_duration_seconds', sa.Float(), nullable=True),
        sa.Column('scan_status', sa.String(length=20), nullable=False),
        sa.Column('error_message', sa.String(), nullable=True),
        sa.Column('performance_metrics', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['scan_sessions.session_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create network_scan_data table
    op.create_table('network_scan_data',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('discovery_id', sa.Integer(), nullable=False),
        sa.Column('open_ports', sa.JSON(), nullable=False),
        sa.Column('total_ports_scanned', sa.Integer(), nullable=False),
        sa.Column('scan_technique', sa.String(length=50), nullable=False),
        sa.Column('services_detected', sa.JSON(), nullable=True),
        sa.Column('os_detection', sa.JSON(), nullable=True),
        sa.Column('nmap_command', sa.String(), nullable=True),
        sa.Column('nmap_output', sa.String(), nullable=True),
        sa.Column('nmap_xml', sa.String(), nullable=True),
        sa.Column('nmap_duration_seconds', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['discovery_id'], ['host_discoveries.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create protocol_probe_results table
    op.create_table('protocol_probe_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('discovery_id', sa.Integer(), nullable=False),
        sa.Column('probe_type', sa.String(length=50), nullable=False),
        sa.Column('target_port', sa.Integer(), nullable=False),
        sa.Column('endpoint_path', sa.String(length=500), nullable=True),
        sa.Column('protocol_hint', sa.String(length=100), nullable=True),
        sa.Column('request_method', sa.String(length=20), nullable=True),
        sa.Column('request_headers', sa.JSON(), nullable=True),
        sa.Column('request_body', sa.String(), nullable=True),
        sa.Column('request_timestamp', sa.DateTime(), nullable=False),
        sa.Column('response_status_code', sa.Integer(), nullable=True),
        sa.Column('response_headers', sa.JSON(), nullable=True),
        sa.Column('response_body', sa.String(), nullable=True),
        sa.Column('response_size_bytes', sa.Integer(), nullable=True),
        sa.Column('response_time_ms', sa.Float(), nullable=True),
        sa.Column('protocol_indicators_found', sa.JSON(), nullable=True),
        sa.Column('confidence_contribution', sa.Float(), nullable=False),
        sa.Column('error_occurred', sa.Boolean(), nullable=False),
        sa.Column('error_message', sa.String(), nullable=True),
        sa.Column('timeout_occurred', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['discovery_id'], ['host_discoveries.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create signature_match_results table
    op.create_table('signature_match_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('discovery_id', sa.Integer(), nullable=False),
        sa.Column('scan_port_signature', sa.String(), nullable=True),
        sa.Column('scan_banner_signature', sa.String(), nullable=True),
        sa.Column('scan_endpoint_signature', sa.String(), nullable=True),
        sa.Column('scan_keyword_signature', sa.String(), nullable=True),
        sa.Column('protocol_id', sa.Integer(), nullable=True),
        sa.Column('protocol_name', sa.String(length=100), nullable=False),
        sa.Column('binary_similarity_score', sa.Float(), nullable=False),
        sa.Column('detailed_analysis_score', sa.Float(), nullable=False),
        sa.Column('combined_final_score', sa.Float(), nullable=False),
        sa.Column('uniqueness_boost_applied', sa.Float(), nullable=False),
        sa.Column('port_evidence', sa.JSON(), nullable=True),
        sa.Column('banner_evidence', sa.JSON(), nullable=True),
        sa.Column('content_evidence', sa.JSON(), nullable=True),
        sa.Column('rpc_evidence', sa.JSON(), nullable=True),
        sa.Column('binary_analysis_time_ms', sa.Float(), nullable=True),
        sa.Column('detailed_analysis_time_ms', sa.Float(), nullable=True),
        sa.Column('total_protocols_checked', sa.Integer(), nullable=True),
        sa.Column('binary_candidates_generated', sa.Integer(), nullable=True),
        sa.Column('match_rank', sa.Integer(), nullable=False),
        sa.Column('above_threshold', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['discovery_id'], ['host_discoveries.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create ai_analysis_results table
    op.create_table('ai_analysis_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('discovery_id', sa.Integer(), nullable=False),
        sa.Column('ai_provider', sa.String(length=50), nullable=False),
        sa.Column('model_used', sa.String(length=100), nullable=False),
        sa.Column('analysis_timestamp', sa.DateTime(), nullable=False),
        sa.Column('input_prompt', sa.String(), nullable=True),
        sa.Column('input_data_hash', sa.String(length=64), nullable=True),
        sa.Column('ai_response_raw', sa.String(), nullable=True),
        sa.Column('ai_confidence', sa.String(length=20), nullable=True),
        sa.Column('ai_reasoning', sa.String(), nullable=True),
        sa.Column('ai_suggested_protocol', sa.String(length=100), nullable=True),
        sa.Column('parsed_successfully', sa.Boolean(), nullable=False),
        sa.Column('parse_error_message', sa.String(), nullable=True),
        sa.Column('tokens_used', sa.Integer(), nullable=True),
        sa.Column('api_cost_usd', sa.Float(), nullable=True),
        sa.Column('response_time_seconds', sa.Float(), nullable=True),
        sa.Column('influenced_final_result', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['discovery_id'], ['host_discoveries.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create validation_results table
    op.create_table('validation_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('discovery_id', sa.Integer(), nullable=False),
        sa.Column('validation_type', sa.String(length=50), nullable=False),
        sa.Column('validated_by', sa.String(length=100), nullable=True),
        sa.Column('validation_timestamp', sa.DateTime(), nullable=False),
        sa.Column('actual_protocol', sa.String(length=100), nullable=True),
        sa.Column('validation_confidence', sa.String(length=20), nullable=False),
        sa.Column('validation_source', sa.String(length=100), nullable=True),
        sa.Column('detection_was_correct', sa.Boolean(), nullable=True),
        sa.Column('detection_was_close', sa.Boolean(), nullable=True),
        sa.Column('false_positive', sa.Boolean(), nullable=False),
        sa.Column('false_negative', sa.Boolean(), nullable=False),
        sa.Column('validation_notes', sa.String(), nullable=True),
        sa.Column('correction_needed', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['discovery_id'], ['host_discoveries.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for performance
    op.create_index('idx_host_discoveries_hostname', 'host_discoveries', ['hostname'])
    op.create_index('idx_host_discoveries_session', 'host_discoveries', ['session_id'])
    op.create_index('idx_host_discoveries_protocol', 'host_discoveries', ['detected_protocol'])
    op.create_index('idx_host_discoveries_confidence', 'host_discoveries', ['confidence_level', 'confidence_score'])
    op.create_index('idx_host_discoveries_timestamp', 'host_discoveries', ['scan_completed_at'])
    
    op.create_index('idx_probe_results_discovery', 'protocol_probe_results', ['discovery_id'])
    op.create_index('idx_probe_results_port', 'protocol_probe_results', ['target_port'])
    op.create_index('idx_probe_results_type', 'protocol_probe_results', ['probe_type'])
    
    op.create_index('idx_signature_matches_discovery', 'signature_match_results', ['discovery_id'])
    op.create_index('idx_signature_matches_protocol', 'signature_match_results', ['protocol_name'])
    op.create_index('idx_signature_matches_score', 'signature_match_results', ['combined_final_score'])
    
    op.create_index('idx_scan_sessions_status', 'scan_sessions', ['status', 'started_at'])
    op.create_index('idx_validation_accuracy', 'validation_results', ['detection_was_correct', 'validation_confidence'])


def downgrade() -> None:
    """Downgrade schema."""
    # Drop indexes
    op.drop_index('idx_validation_accuracy', 'validation_results')
    op.drop_index('idx_scan_sessions_status', 'scan_sessions')
    op.drop_index('idx_signature_matches_score', 'signature_match_results')
    op.drop_index('idx_signature_matches_protocol', 'signature_match_results')
    op.drop_index('idx_signature_matches_discovery', 'signature_match_results')
    op.drop_index('idx_probe_results_type', 'protocol_probe_results')
    op.drop_index('idx_probe_results_port', 'protocol_probe_results')
    op.drop_index('idx_probe_results_discovery', 'protocol_probe_results')
    op.drop_index('idx_host_discoveries_timestamp', 'host_discoveries')
    op.drop_index('idx_host_discoveries_confidence', 'host_discoveries')
    op.drop_index('idx_host_discoveries_protocol', 'host_discoveries')
    op.drop_index('idx_host_discoveries_session', 'host_discoveries')
    op.drop_index('idx_host_discoveries_hostname', 'host_discoveries')
    
    # Drop tables in reverse order (to respect foreign key constraints)
    op.drop_table('validation_results')
    op.drop_table('ai_analysis_results')
    op.drop_table('signature_match_results')
    op.drop_table('protocol_probe_results')
    op.drop_table('network_scan_data')
    op.drop_table('host_discoveries')
    op.drop_table('scan_sessions')
