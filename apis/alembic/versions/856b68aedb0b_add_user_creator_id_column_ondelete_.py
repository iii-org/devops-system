"""add user creator_id column ondelete funtion

Revision ID: 856b68aedb0b
Revises: 39ac2afbe86f
Create Date: 2021-05-05 10:15:50.725992

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '856b68aedb0b'
down_revision = '39ac2afbe86f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('projects_owner_id_fkey', 'projects', type_='foreignkey')
    op.drop_constraint('projects_creator_id_fkey', 'projects', type_='foreignkey')
    op.create_foreign_key(None, 'projects', 'user', ['owner_id'], ['id'], ondelete='SET NULL')
    op.create_foreign_key(None, 'projects', 'user', ['creator_id'], ['id'], ondelete='SET NULL')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'projects', type_='foreignkey')
    op.drop_constraint(None, 'projects', type_='foreignkey')
    op.create_foreign_key('projects_creator_id_fkey', 'projects', 'user', ['creator_id'], ['id'])
    op.create_foreign_key('projects_owner_id_fkey', 'projects', 'user', ['owner_id'], ['id'])
    # ### end Alembic commands ###
