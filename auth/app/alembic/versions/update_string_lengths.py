"""Update string lengths in User and UserSocialAccount models

Revision ID: def987654321
Revises: abc123456789
Create Date: 2024-10-19 12:30:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'def987654321'
down_revision = 'abc123456789'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Update string lengths for User model
    op.alter_column('users', 'email', type_=sa.String(255), existing_type=sa.String(), postgresql_using='email::varchar(255)')
    op.alter_column('users', 'username', type_=sa.String(50), existing_type=sa.String(), postgresql_using='username::varchar(50)')
    op.alter_column('users', 'hashed_password', type_=sa.String(128), existing_type=sa.String(), postgresql_using='hashed_password::varchar(128)')
    op.alter_column('users', 'full_name', type_=sa.String(100), existing_type=sa.String(), postgresql_using='full_name::varchar(100)')

    # Update string lengths for UserSocialAccount model
    op.alter_column('user_social_accounts', 'provider', type_=sa.String(50), existing_type=sa.String(), postgresql_using='provider::varchar(50)')
    op.alter_column('user_social_accounts', 'provider_user_id', type_=sa.String(255), existing_type=sa.String(), postgresql_using='provider_user_id::varchar(255)')
    op.alter_column('user_social_accounts', 'email', type_=sa.String(255), existing_type=sa.String(), postgresql_using='email::varchar(255)')


def downgrade() -> None:
    # Rollback string lengths to previous state if needed
    op.alter_column('users', 'email', type_=sa.String(), existing_type=sa.String(255), postgresql_using='email::varchar')
    op.alter_column('users', 'username', type_=sa.String(), existing_type=sa.String(50), postgresql_using='username::varchar')
    op.alter_column('users', 'hashed_password', type_=sa.String(), existing_type=sa.String(128), postgresql_using='hashed_password::varchar')
    op.alter_column('users', 'full_name', type_=sa.String(), existing_type=sa.String(100), postgresql_using='full_name::varchar')

    op.alter_column('user_social_accounts', 'provider', type_=sa.String(), existing_type=sa.String(50), postgresql_using='provider::varchar')
    op.alter_column('user_social_accounts', 'provider_user_id', type_=sa.String(), existing_type=sa.String(255), postgresql_using='provider_user_id::varchar')
    op.alter_column('user_social_accounts', 'email', type_=sa.String(), existing_type=sa.String(255), postgresql_using='email::varchar')
