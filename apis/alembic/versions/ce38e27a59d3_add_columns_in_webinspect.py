"""add_columns_in_webinspect

Revision ID: ce38e27a59d3
Revises: 545c558f6cfb
Create Date: 2023-04-11 12:29:43.164372

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ce38e27a59d3'
down_revision = '545c558f6cfb'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('web_inspect', sa.Column('state', sa.JSON(), nullable=True))
    op.add_column('web_inspect', sa.Column('report_status', sa.String(), nullable=True))
    op.add_column('web_inspect', sa.Column('log', sa.String(), nullable=True))
    op.drop_column('web_inspect', 'stats')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('web_inspect', sa.Column('stats', sa.VARCHAR(), autoincrement=False, nullable=True))
    op.drop_column('web_inspect', 'log')
    op.drop_column('web_inspect', 'report_status')
    op.drop_column('web_inspect', 'state')
    # ### end Alembic commands ###