"""add_column_tags_custom_paths_in_Release

Revision ID: e25e528d33c0
Revises: da4c2828fb1c
Create Date: 2022-05-09 10:36:29.447639

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'e25e528d33c0'
down_revision = 'da4c2828fb1c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('release', sa.Column('custom_paths', postgresql.ARRAY(sa.String()), nullable=True))
    op.add_column('release', sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('release', 'tags')
    op.drop_column('release', 'custom_paths')
    # ### end Alembic commands ###
