"""
Test configuration for pytest.
Ensures tests use test_depin database instead of production depin database.
"""
import os

# Set test database URL BEFORE any other imports
os.environ['DATABASE_URL'] = 'postgresql://simon@localhost/test_depin'
os.environ['USE_DOCKER_CONFIG'] = 'true'  # Required for DATABASE_URL to be used

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from core.database import get_db_session
from models.ledger import Base as LedgerBase
from models.validator import Base as ValidatorBase


@pytest.fixture(scope="function", autouse=True)
def cleanup_test_data():
    """Clean up test data before and after each test."""
    # Clean up before test
    _clean_test_data()
    
    yield
    
    # Clean up after test
    _clean_test_data()


def _clean_test_data():
    """Helper function to clean test data."""
    try:
        with get_db_session() as session:
            # Clean up ledger test data
            session.execute(text("DELETE FROM ledger_publish_logs WHERE publishing_agent LIKE '%Test%'"))
            session.execute(text("DELETE FROM ledger_batches WHERE blockchain_network = 'zkSync Era Sepolia'"))
            session.execute(text("DELETE FROM ledger_connection_logs WHERE agent_name LIKE '%Test%'"))
            session.commit()
    except Exception as e:
        print(f"Warning: Could not clean up test data: {e}")


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Set up test database configuration for all tests."""
    # Force tests to use test database
    original_db_url = os.environ.get('DATABASE_URL')
    test_db_url = 'postgresql://simon@localhost/test_depin'
    os.environ['DATABASE_URL'] = test_db_url
    
    print(f"🧪 Tests will use database: test_depin")
    
    # Verify connection to test database
    try:
        with get_db_session() as session:
            db_name = session.execute(text('SELECT current_database()')).scalar()
            assert db_name == 'test_depin', f"Expected test_depin, got {db_name}"
            print(f"✅ Connected to test database: {db_name}")
    except Exception as e:
        pytest.fail(f"Failed to connect to test database: {e}")
    
    yield
    
    # Restore original database URL after tests
    if original_db_url:
        os.environ['DATABASE_URL'] = original_db_url
    else:
        os.environ.pop('DATABASE_URL', None)


@pytest.fixture(scope="session")
def test_engine():
    """Create test database engine."""
    test_db_url = 'postgresql://simon@localhost/test_depin'
    engine = create_engine(test_db_url, echo=False)
    return engine


@pytest.fixture(scope="session")
def test_session_factory(test_engine):
    """Create test session factory."""
    return sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def test_session(test_session_factory):
    """Create a test database session for each test function."""
    session = test_session_factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(scope="session", autouse=True)
def ensure_test_tables_exist(test_engine):
    """Ensure all necessary tables exist in test database."""
    try:
        print("🔧 Ensuring test database tables exist...")
        
        # Create ledger tables if they don't exist
        LedgerBase.metadata.create_all(bind=test_engine, checkfirst=True)
        
        # Check if validator_scans table exists, if not create it or add some test data
        with test_engine.connect() as conn:
            result = conn.execute(text("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_name = 'validator_scans' AND table_schema = 'public'
            """))
            
            if not result.fetchone():
                print("⚠️  validator_scans table not found in test database")
                # Create a minimal validator_scans table for testing
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS validator_scans (
                        id SERIAL PRIMARY KEY,
                        validator_address_id INTEGER,
                        scan_date TIMESTAMP,
                        ip_address VARCHAR(255),
                        score INTEGER,
                        scan_hash VARCHAR(255),
                        scan_results JSON,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        failed BOOLEAN DEFAULT FALSE,
                        version VARCHAR(255),
                        signature_created BOOLEAN DEFAULT FALSE
                    )
                """))
                
                # Insert some test scan records
                for i in range(1, 11):
                    conn.execute(text("""
                        INSERT INTO validator_scans (
                            validator_address_id, scan_date, ip_address, score, 
                            scan_hash, scan_results, created_at
                        ) VALUES (
                            :addr_id, CURRENT_TIMESTAMP, :ip, :score, 
                            :hash, :results, CURRENT_TIMESTAMP
                        )
                    """), {
                        'addr_id': 1,
                        'ip': f'192.168.1.{i}',
                        'score': 75 + i,
                        'hash': f'test_hash_{i}',
                        'results': '{"test": true}'
                    })
                
                conn.commit()
                print("✅ Created validator_scans table with test data")
            else:
                # Check if we have enough test records
                count_result = conn.execute(text("SELECT COUNT(*) FROM validator_scans"))
                count = count_result.scalar()
                if count < 10:
                    # Add more test records
                    for i in range(count + 1, 11):
                        conn.execute(text("""
                            INSERT INTO validator_scans (
                                validator_address_id, scan_date, ip_address, score, 
                                scan_hash, scan_results, created_at
                            ) VALUES (
                                :addr_id, CURRENT_TIMESTAMP, :ip, :score, 
                                :hash, :results, CURRENT_TIMESTAMP
                            )
                        """), {
                            'addr_id': 1,
                            'ip': f'192.168.1.{i}',
                            'score': 75 + i,
                            'hash': f'test_hash_{i}',
                            'results': '{"test": true}'
                        })
                    conn.commit()
                    print(f"✅ Added test records to validator_scans (now {10} total)")
                else:
                    print(f"✅ validator_scans table exists with {count} records")
        
        print("✅ Test database setup complete")
        
    except Exception as e:
        print(f"❌ Failed to set up test database: {e}")
        raise


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "database: mark test as requiring database access"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
