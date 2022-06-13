"""'create_harbor_scan'

Revision ID: a25a2a0bb803
Revises: 4aa317ad8650
Create Date: 2022-05-19 17:36:26.419260

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a25a2a0bb803'
down_revision = '4aa317ad8650'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('harbor_scan',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=True),
    sa.Column('harbor_project_id', sa.Integer(), nullable=True),
    sa.Column('branch', sa.String(), nullable=True),
    sa.Column('commit', sa.String(), nullable=True),
    sa.Column('digest', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('finished', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('harbor_scan')
    # ### end Alembic commands ###