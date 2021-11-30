"""create_CMAS_table

Revision ID: c0ea091d1315
Revises: 3c4ab1602ad4
Create Date: 2021-11-30 16:38:20.421388

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c0ea091d1315'
down_revision = '3c4ab1602ad4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('CMAS',
    sa.Column('task_id', sa.String(), nullable=False),
    sa.Column('cm_project_id', sa.Integer(), nullable=True),
    sa.Column('repo_id', sa.Integer(), nullable=True),
    sa.Column('branch', sa.String(), nullable=True),
    sa.Column('commit_id', sa.String(), nullable=True),
    sa.Column('run_at', sa.DateTime(), nullable=True),
    sa.Column('scan_final_status', sa.String(), nullable=True),
    sa.Column('stats', sa.String(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('finished', sa.Boolean(), nullable=True),
    sa.Column('filename', sa.String(), nullable=True),
    sa.Column('upload_id', sa.Integer(), nullable=True),
    sa.Column('sha256', sa.String(), nullable=True),
    sa.Column('a_mode', sa.Integer(), nullable=True),
    sa.Column('a_report_type', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['repo_id'], ['project_plugin_relation.git_repository_id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('task_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('CMAS')
    # ### end Alembic commands ###