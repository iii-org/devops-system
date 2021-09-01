"""add_column_alert_in_project

Revision ID: 4ecd1fce7b33
Revises: b0fe26c527b3
Create Date: 2021-08-16 12:22:57.308552

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4ecd1fce7b33'
down_revision = 'b0fe26c527b3'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('projects', sa.Column('alert', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('projects', 'alert')
    # ### end Alembic commands ###
