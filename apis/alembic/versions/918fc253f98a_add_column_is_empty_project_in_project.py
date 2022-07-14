"""add_column_is_empty_project_in_Project

Revision ID: 918fc253f98a
Revises: 89935f1c41eb
Create Date: 2022-07-14 14:23:25.012926

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '918fc253f98a'
down_revision = '89935f1c41eb'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('projects', sa.Column('is_empty_project', sa.Boolean(), server_default='false', nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('projects', 'is_empty_project')
    # ### end Alembic commands ###
