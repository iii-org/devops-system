"""add_report_id_in_webinspect

Revision ID: 545c558f6cfb
Revises: d3e9ebe9efa7
Create Date: 2023-04-06 15:43:28.345263

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '545c558f6cfb'
down_revision = 'd3e9ebe9efa7'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('web_inspect', sa.Column('report_id', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('web_inspect', 'report_id')
    # ### end Alembic commands ###
