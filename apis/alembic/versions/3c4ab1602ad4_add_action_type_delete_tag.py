"""add_action_type_DELETE_TAG

Revision ID: 3c4ab1602ad4
Revises: 54dc194b8646
Create Date: 2021-11-23 00:35:16.945268

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3c4ab1602ad4'
down_revision = '54dc194b8646'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE actiontype ADD VALUE 'DELETE_TAG'")


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###