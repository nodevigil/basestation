# GitHub Copilot Agent Instructions

This repository is a Python-based campaign automation system for managing campaign executions, email sending, lead management, and reporting.

## Code Standards

### Required Before Each Commit
- Run `black .` and `flake8 .` to ensure code style and linting standards are met.
- Ensure all new and existing unit tests pass by running `pytest`.
- Update the `README.md` if you add new features or change existing functionality.
- Keep this Copilot Instructions file up to date with any changes to the repository structure.
- Document all public functions and classes with clear docstrings.
- Use type hints for all function signatures and class attributes.

### Python Patterns
- Use idiomatic Python and follow PEP8 style guidelines.
- Prefer composition over inheritance unless inheritance is clearly justified.
- Functions and methods should be small and focused (single-responsibility principle).
- Avoid code duplication; use utility functions or classes where appropriate.
- Handle exceptions gracefully and log errors using the standard `logging` module.
- Use context managers (`with` statements) for resource management (e.g., database connections).

### Database and Data Handling
- Use parameterized queries with psycopg2 to prevent SQL injection.
- Always close database connections and cursors (preferably with context managers).
- Validate and sanitize all external input.
- When working with JSON fields, ensure proper serialization/deserialization.
- The database is depin the user is simon

### Testing
- Place all tests in the `tests/` directory.
- Write unit tests for all new features and bug fixes.
- Use fixtures for setting up test data.
- Mock external dependencies (e.g., database, email sending) in tests.

## Development Flow
- Install dependencies: `pip install -r requirements.txt`
- Run the development server or scripts as described in the `README.md`
- Run tests: `pytest`
- Lint and format: `black .` and `flake8 .`

## Repository Structure
- `config.py`: Configuration (database, limits, etc.)
- `tests/`: Unit and integration tests
- `README.md`: Project documentation

## Key Guidelines
1. Use clear, descriptive variable and function names.
2. Write docstrings for all public methods and classes.
3. Log important actions and errors using the `logging` module.
4. Avoid hardcoding values; use configuration files or environment variables.
5. Ensure all database migrations and schema changes are documented.
6. When adding new modules or features, update the documentation and Copilot Instructions.
7. Use type hints and static analysis tools to catch errors early.
8. When handling sensitive data (e.g., emails), follow best security practices.

## Documentation

1. Append changes to the change_log.md file for every update.
2. Keep the readme updated!

Run python3 only when you've done the source. Use pytest!
---