"""'rename_ui_route_data'

Revision ID: 89935f1c41eb
Revises: d7962cfd2601
Create Date: 2022-06-18 12:33:33.125684

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '89935f1c41eb'
down_revision = 'd7962cfd2601'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('ui_route_data',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('role', sa.String(), nullable=False),
    sa.Column('parent', sa.Integer(), nullable=True),
    sa.Column('old_brother', sa.Integer(), nullable=True),
    sa.Column('visible', sa.Boolean(), nullable=True),
    sa.Column('ui_route', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id', 'name', 'role')
    )
    op.drop_table('ui_route')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('ui_route',
    sa.Column('id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('name', sa.VARCHAR(), autoincrement=False, nullable=False),
    sa.Column('role', sa.VARCHAR(), autoincrement=False, nullable=False),
    sa.Column('parent', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('old_brother', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('visible', sa.BOOLEAN(), autoincrement=False, nullable=True),
    sa.Column('ui_route', postgresql.JSON(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
    sa.Column('updated_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', 'name', 'role', name='ui_route_pkey')
    )
    op.drop_table('ui_route_data')
    # ### end Alembic commands ###
