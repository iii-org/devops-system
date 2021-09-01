"""Add activity enum type

Revision ID: 1e88c025260e
Revises: 97b3f3995a94
Create Date: 2021-08-02 10:47:04.751572

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '1e88c025260e'
down_revision = '97b3f3995a94'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE actiontype ADD VALUE 'DELETE_ISSUE'")


def downgrade():
    # We won't put things back
    pass
