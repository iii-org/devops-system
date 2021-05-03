"""remove project overview and issue rank
Revision ID: a460da0d9a8c
Revises: b363e9236a88
Create Date: 2021-04-21 18:05:54.000094
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a460da0d9a8c'
down_revision = 'b363e9236a88'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('issue_rank')
    op.drop_table('project_ovewview')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('project_ovewview',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('project_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('overdue_issue_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('no_started_issue_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='project_ovewview_pkey')
    )
    op.create_table('issue_rank',
    sa.Column('user_id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('user_name', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('unclosed_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('project_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('user_id', name='issue_rank_pkey')
    )
    # ### end Alembic commands ###