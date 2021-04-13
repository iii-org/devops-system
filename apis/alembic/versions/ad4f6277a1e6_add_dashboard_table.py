"""add dashboard table

Revision ID: ad4f6277a1e6
Revises: 9c79db35e936
Create Date: 2021-04-12 10:49:56.503363

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ad4f6277a1e6'
down_revision = '9c79db35e936'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('issue_rank',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('user_name', sa.String(), nullable=True),
    sa.Column('unclosed_count', sa.Integer(), nullable=True),
    sa.Column('prject_count', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('user_id')
    )
    op.create_table('project_member_count',
    sa.Column('project_id', sa.Integer(), nullable=False),
    sa.Column('project_name', sa.String(), nullable=True),
    sa.Column('member_count', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('project_id')
    )
    op.create_table('project_ovewview',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('project_count', sa.Integer(), nullable=True),
    sa.Column('overdue_issue_count', sa.Integer(), nullable=True),
    sa.Column('no_started_issue_count', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.add_column('redmine_project', sa.Column('closed_issue_count', sa.Integer(), nullable=True))
    op.add_column('redmine_project', sa.Column('complete_percent', sa.Float(), nullable=True))
    op.add_column('redmine_project', sa.Column('expired_day', sa.Integer(), nullable=True))
    op.add_column('redmine_project', sa.Column('member_count', sa.Integer(), nullable=True))
    op.add_column('redmine_project', sa.Column('pm_user_id', sa.Integer(), nullable=True))
    op.add_column('redmine_project', sa.Column('pm_user_name', sa.String(), nullable=True))
    op.add_column('redmine_project', sa.Column('total_issue_count', sa.Integer(), nullable=True))
    op.add_column('redmine_project', sa.Column('unclosed_issue_count', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('redmine_project', 'unclosed_issue_count')
    op.drop_column('redmine_project', 'total_issue_count')
    op.drop_column('redmine_project', 'pm_user_name')
    op.drop_column('redmine_project', 'pm_user_id')
    op.drop_column('redmine_project', 'member_count')
    op.drop_column('redmine_project', 'expired_day')
    op.drop_column('redmine_project', 'complete_percent')
    op.drop_column('redmine_project', 'closed_issue_count')
    op.drop_table('project_ovewview')
    op.drop_table('project_member_count')
    op.drop_table('issue_rank')
    # ### end Alembic commands ###
