"""add_activity_enum_modify_hook

Revision ID: daaf84c340cd
Revises: 1f0e2963b684
Create Date: 2022-01-07 14:29:18.562814

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'daaf84c340cd'
down_revision = '1f0e2963b684'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE actiontype ADD VALUE 'MODIFY_HOOK'")


def downgrade():
    # We won't put things back
    pass
