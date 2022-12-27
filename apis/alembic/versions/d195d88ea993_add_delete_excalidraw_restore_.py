"""add DELETE_EXCALIDRAW,RESTORE_EXCALIDRAW_HISTORY activity

Revision ID: d195d88ea993
Revises: aac2d1158a8c
Create Date: 2022-12-21 10:16:06.330068

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd195d88ea993'
down_revision = 'aac2d1158a8c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE actiontype ADD VALUE IF NOT EXISTS 'DELETE_EXCALIDRAW'")
        op.execute("ALTER TYPE actiontype ADD VALUE IF NOT EXISTS 'RESTORE_EXCALIDRAW_HISTORY'")
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###
