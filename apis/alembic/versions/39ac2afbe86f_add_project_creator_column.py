"""add project creator column

Revision ID: 39ac2afbe86f
Revises: ec4c3aab9b73
Create Date: 2021-05-04 17:06:28.369384

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '39ac2afbe86f'
down_revision = 'ec4c3aab9b73'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('projects', sa.Column('creator_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'projects', 'user', ['creator_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'projects', type_='foreignkey')
    op.drop_column('projects', 'creator_id')
    # ### end Alembic commands ###
