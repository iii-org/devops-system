"""add_point_in_redmine_issue

Revision ID: 6eef61199a95
Revises: d10a9ad9f863
Create Date: 2021-09-08 02:39:40.225088

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6eef61199a95'
down_revision = 'd10a9ad9f863'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('redmine_issue', sa.Column('point', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('redmine_issue', 'point')
    # ### end Alembic commands ###
