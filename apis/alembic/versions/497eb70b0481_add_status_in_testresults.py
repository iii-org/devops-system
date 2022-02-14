"""add_status_in_TestResults

Revision ID: 497eb70b0481
Revises: 3d49b0bdda9e
Create Date: 2022-02-14 14:41:42.255850

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '497eb70b0481'
down_revision = '3d49b0bdda9e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('test_results', sa.Column('status', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('test_results', 'status')
    # ### end Alembic commands ###
