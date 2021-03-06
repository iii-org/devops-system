"""Change checkmarx table primary key

Revision ID: 0fb7e7cc03a0
Revises: 952a4cc50baf
Create Date: 2020-12-07 15:49:33.051357

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0fb7e7cc03a0'
down_revision = '952a4cc50baf'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('checkmarx_pkey', 'checkmarx', type_='primary')
    op.create_primary_key('checkmarx_pkey', 'checkmarx', ['scan_id'])
    op.alter_column('checkmarx', 'cm_project_id',
               existing_type=sa.INTEGER(),
               nullable=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('checkmarx', 'cm_project_id',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.drop_constraint('checkmarx_pkey', 'checkmarx', type_='primary')
    op.create_primary_key('checkmarx_pkey', 'checkmarx', ['cm_project_id'])
    # ### end Alembic commands ###
