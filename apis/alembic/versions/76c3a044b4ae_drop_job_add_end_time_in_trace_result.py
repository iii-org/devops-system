"""drop_job_add_end_time_in_trace_result

Revision ID: 76c3a044b4ae
Revises: eab8d977bfb9
Create Date: 2021-08-26 07:20:23.880493

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '76c3a044b4ae'
down_revision = 'eab8d977bfb9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('trace_result', sa.Column('finish_time', sa.DateTime(), nullable=True))
    op.drop_column('trace_result', 'current_job')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('trace_result', sa.Column('current_job', postgresql.BYTEA(), autoincrement=False, nullable=True))
    op.drop_column('trace_result', 'finish_time')
    # ### end Alembic commands ###
