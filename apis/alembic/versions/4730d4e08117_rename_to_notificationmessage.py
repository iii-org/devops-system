"""rename to NotificationMessage

Revision ID: 4730d4e08117
Revises: 071e6082e75b
Create Date: 2021-12-27 17:11:50.539313

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '4730d4e08117'
down_revision = '071e6082e75b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('notification_message',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('message', sa.String(), nullable=False),
                    sa.Column('type_id', sa.Integer(), nullable=False),
                    sa.Column('type_parameter', sa.JSON(), nullable=True),
                    sa.Column('no_deadline', sa.Boolean(), nullable=False),
                    sa.Column('due_datetime', sa.DateTime(), nullable=True),
                    sa.Column('creator_id', sa.Integer(), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.ForeignKeyConstraint(['creator_id'], ['user.id'], ondelete='SET NULL'),
                    sa.PrimaryKeyConstraint('id')
                    )
    op.create_table('notification_message_reply_slip',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('message_id', sa.Integer(), nullable=True),
                    sa.Column('user_id', sa.Integer(), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.ForeignKeyConstraint(['message_id'], ['notification_message.id'], ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id')
                    )
    op.drop_table('message_reply_slip')
    op.drop_table('message')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('message',
                    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
                    sa.Column('message', sa.VARCHAR(), autoincrement=False, nullable=False),
                    sa.Column('type_id', sa.INTEGER(), autoincrement=False, nullable=False),
                    sa.Column('type_parameter', postgresql.JSON(
                        astext_type=sa.Text()), autoincrement=False, nullable=True),
                    sa.Column('no_deadline', sa.BOOLEAN(), autoincrement=False, nullable=False),
                    sa.Column('due_datetime', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
                    sa.Column('creator_id', sa.INTEGER(), autoincrement=False, nullable=True),
                    sa.Column('created_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
                    sa.Column('updated_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
                    sa.ForeignKeyConstraint(['creator_id'], ['user.id'],
                                            name='message_creator_id_fkey', ondelete='SET NULL'),
                    sa.PrimaryKeyConstraint('id', name='message_pkey')
                    )
    op.create_table('message_reply_slip',
                    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
                    sa.Column('message_id', sa.INTEGER(), autoincrement=False, nullable=True),
                    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=True),
                    sa.Column('created_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
                    sa.ForeignKeyConstraint(['message_id'], ['message.id'],
                                            name='message_reply_slip_message_id_fkey', ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['user_id'], ['user.id'],
                                            name='message_reply_slip_user_id_fkey', ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id', name='message_reply_slip_pkey')
                    )
    op.drop_table('notification_message_reply_slip')
    op.drop_table('notification_message')
    # ### end Alembic commands ###
