"""change Application Registry_id as foreign key

Revision ID: 83e7e83f406b
Revises: bca34d393dd5
Create Date: 2021-08-23 16:29:18.994702

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '83e7e83f406b'
down_revision = 'bca34d393dd5'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key('application_registry_id_fkey', 'application', 'registries', ['registry_id'], ['registries_id'])
    op.drop_column('registries', 'disabled')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('registries', sa.Column('disabled', sa.BOOLEAN(), autoincrement=False, nullable=True))
    op.drop_constraint('application_registry_id_fkey', 'application', type_='foreignkey')
    # ### end Alembic commands ###
