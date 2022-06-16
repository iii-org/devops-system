"""'create_ui_route_md5'

Revision ID: 28a250dba93a
Revises: b40ffa55cf93
Create Date: 2022-06-16 17:47:07.074025

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '28a250dba93a'
down_revision = 'b40ffa55cf93'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('ui_route_file',
    sa.Column('file_name', sa.String(), nullable=False),
    sa.Column('file_md5', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('file_name')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('ui_route_file')
    # ### end Alembic commands ###
