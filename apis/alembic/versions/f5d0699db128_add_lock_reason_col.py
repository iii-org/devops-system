"""'add_lock_reason_col'

Revision ID: f5d0699db128
Revises: b96d6e6491cb
Create Date: 2022-02-23 09:32:56.508561

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f5d0699db128'
down_revision = 'b96d6e6491cb'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('projects', sa.Column('lock_reason', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('projects', 'lock_reason')
    # ### end Alembic commands ###