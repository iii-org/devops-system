"""add_column_sequence_in_sbom

Revision ID: 60ae38472154
Revises: f373f135b9d7
Create Date: 2022-08-09 17:35:28.902456

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '60ae38472154'
down_revision = 'f373f135b9d7'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('sbom', sa.Column('sequence', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('sbom', 'sequence')
    # ### end Alembic commands ###