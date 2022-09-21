"""add a activity for delete json file

Revision ID: 9cba7afff76b
Revises: f1787557741f
Create Date: 2022-09-21 16:32:13.354089

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9cba7afff76b'
down_revision = 'f1787557741f'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE actiontype ADD VALUE IF NOT EXISTS 'DELETE_SIDEEX_JSONFILE'")


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###