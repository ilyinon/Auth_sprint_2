"""Add session_date column

Revision ID: 15a5d4acd787
Revises: f19105242932
Create Date: 2024-10-11 19:38:22.282228

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "15a5d4acd787"
down_revision: Union[str, None] = "f8dd8025d909"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
            CREATE TABLE sessions (
                id UUID NOT NULL,
                user_id UUID NOT NULL,
                user_agent TEXT,
                user_action VARCHAR NOT NULL,
                session_date DATE NOT NULL,
                created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                modified_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE (id, session_date)
            ) PARTITION BY RANGE (session_date);
            """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION create_sessions_partition(partition_date DATE)
        RETURNS VOID AS $$
        BEGIN
            EXECUTE format('CREATE TABLE sessions_%s PARTITION OF sessions FOR VALUES FROM (date ''%s'') TO (date ''%s'');',
                             to_char(partition_date, 'YYYYMMDD'), partition_date, partition_date + INTERVAL '1 day');
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    op.execute("SELECT create_sessions_partition(CURRENT_DATE);")

    # ### end Alembic commands ###


def downgrade() -> None:
    op.execute("DROP FUNCTION create_sessions_partition(DATE);")
    op.drop_table("sessions")
    # ### end Alembic commands ###
