"""add_table_PipelineExecution

Revision ID: 3150679cd670
Revises: a8860027a552
Create Date: 2023-01-07 17:28:19.347025

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '3150679cd670'
down_revision = 'a8860027a552'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('pipeline_execution',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=True),
    sa.Column('branch', sa.String(), nullable=True),
    sa.Column('commit_id', sa.String(), nullable=True),
    sa.Column('run_branches', postgresql.ARRAY(sa.String()), nullable=True),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('pipeline_execution')
    # ### end Alembic commands ###
