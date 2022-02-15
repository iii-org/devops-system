"""create_ui_router_table

Revision ID: 9b28682a8925
Revises: 497eb70b0481
Create Date: 2022-02-15 17:13:58.603797

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9b28682a8925'
down_revision = '497eb70b0481'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('ui_route',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('route_name', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('route_name')
    )
    op.create_table('ui_route_user_role_relation',
    sa.Column('ui_route_id', sa.Integer(), nullable=False),
    sa.Column('user_role', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['ui_route_id'], ['ui_route.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('ui_route_id', 'user_role')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('ui_route_user_role_relation')
    op.drop_table('ui_route')
    # ### end Alembic commands ###