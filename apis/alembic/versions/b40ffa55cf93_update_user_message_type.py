"""update_user_message_type

Revision ID: b40ffa55cf93
Revises: 3db576758a28
Create Date: 2022-06-16 15:16:52.801785

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b40ffa55cf93'
down_revision = '3db576758a28'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user_message_type',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('notification', sa.Boolean(), nullable=True),
    sa.Column('mail', sa.Boolean(), nullable=True),
    sa.Column('teams', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id')
    )
    op.drop_table('user_notify_type')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user_notify_type',
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('notification', sa.BOOLEAN(), autoincrement=False, nullable=True),
    sa.Column('mail', sa.BOOLEAN(), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['projects.id'], name='user_notify_type_user_id_fkey', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id', name='user_notify_type_pkey')
    )
    op.drop_table('user_message_type')
    # ### end Alembic commands ###
