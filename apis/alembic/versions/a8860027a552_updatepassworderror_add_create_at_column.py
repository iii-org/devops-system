"""UpdatePasswordError add create_at column

Revision ID: a8860027a552
Revises: d195d88ea993
Create Date: 2023-01-03 14:37:58.180516

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a8860027a552'
down_revision = 'd195d88ea993'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('update_password_error', sa.Column('created_at', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('update_password_error', 'created_at')
    # ### end Alembic commands ###