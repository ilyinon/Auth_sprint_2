"""Add UserSocialAccount model

Revision ID: abc123456789
Revises: 15a5d4acd787
Create Date: 2024-10-19 12:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'abc123456789'
down_revision = '15a5d4acd787'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create the user_social_accounts table
    op.create_table(
        'user_social_accounts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider', sa.String(), nullable=False),
        sa.Column('provider_user_id', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('modified_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    # Drop the user_social_accounts table
    op.drop_table('user_social_accounts')