"""project add field image_auto_del

Revision ID: c0395dc664f3
Revises: 6a1bd1326e46
Create Date: 2023-06-12 18:18:31.902182

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c0395dc664f3'
down_revision = '6a1bd1326e46'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('projects', sa.Column('image_auto_del', sa.Boolean(), server_default='true', nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('projects', 'image_auto_del')
    # ### end Alembic commands ###