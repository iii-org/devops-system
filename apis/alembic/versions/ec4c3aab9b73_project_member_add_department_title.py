"""project member add department title

Revision ID: ec4c3aab9b73
Revises: 63cac0772a9c
Create Date: 2021-05-04 11:27:10.715603

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ec4c3aab9b73'
down_revision = '63cac0772a9c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('project_member', sa.Column('department', sa.String(), nullable=True))
    op.add_column('project_member', sa.Column('title', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('project_member', 'title')
    op.drop_column('project_member', 'department')
    # ### end Alembic commands ###