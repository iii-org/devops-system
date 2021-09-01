"""Delete image coloumn at Application Table

Revision ID: 90a8f40d4f2c
Revises: 9e79c81782e5
Create Date: 2021-08-31 10:51:22.015354

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '90a8f40d4f2c'
down_revision = '9e79c81782e5'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('application', 'image')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('application', sa.Column('image', sa.VARCHAR(), autoincrement=False, nullable=True))
    # ### end Alembic commands ###
