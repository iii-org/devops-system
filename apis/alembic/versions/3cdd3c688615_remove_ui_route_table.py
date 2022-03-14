"""'remove_ui_route_table'

Revision ID: 3cdd3c688615
Revises: 4da96366dc33
Create Date: 2022-03-14 16:57:15.947385

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '3cdd3c688615'
down_revision = '4da96366dc33'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('ui_route_user_role_relation')
    op.drop_table('ui_route')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('ui_route',
                    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
                    sa.Column('route_name', sa.VARCHAR(), autoincrement=False, nullable=False),
                    sa.Column('created_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
                    sa.Column('updated_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
                    sa.PrimaryKeyConstraint('id', name='ui_route_pkey'),
                    sa.UniqueConstraint('route_name', name='ui_route_route_name_key')
                    )
    op.create_table('ui_route_user_role_relation',
                    sa.Column('ui_route_id', sa.INTEGER(), autoincrement=False, nullable=False),
                    sa.Column('user_role', sa.INTEGER(), autoincrement=False, nullable=False),
                    sa.Column('created_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
                    sa.ForeignKeyConstraint(['ui_route_id'], ['ui_route.id'],
                                            name='ui_route_user_role_relation_ui_route_id_fkey', ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('ui_route_id', 'user_role', name='ui_route_user_role_relation_pkey')
                    )
    # ### end Alembic commands ###
