"""add_table_server_type

Revision ID: d68db624b8cf
Revises: 7df95055d195
Create Date: 2021-09-30 17:35:53.022107

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd68db624b8cf'
down_revision = '7df95055d195'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('server_type',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('server', sa.String(), nullable=True),
    sa.Column('type', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('server_type')
    # ### end Alembic commands ###