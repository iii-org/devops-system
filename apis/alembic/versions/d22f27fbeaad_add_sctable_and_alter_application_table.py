"""add_sctable_and_alter_application_table

Revision ID: d22f27fbeaad
Revises: 54828c352925
Create Date: 2023-01-30 10:16:36.204364

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd22f27fbeaad'
down_revision = '54828c352925'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('storage_class',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('cluster_id', sa.Integer(), nullable=True),
    sa.Column('name', sa.String(), nullable=True),
    sa.Column('disabled', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['cluster_id'], ['cluster.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.add_column('application', sa.Column('storage_class_id', sa.Integer(), nullable=True))
    op.add_column('application', sa.Column('order', sa.Integer(), nullable=True, server_default='0'))
    # ### end Alembic commands ###
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE actiontype ADD VALUE IF NOT EXISTS 'ENABLED_SC'")
        op.execute("ALTER TYPE actiontype ADD VALUE IF NOT EXISTS 'DISABLED_SC'")


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('application', 'order')
    op.drop_column('application', 'storage_class_id')
    op.drop_table('storage_class')
    # ### end Alembic commands ###
